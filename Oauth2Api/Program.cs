using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Oauth2Api.Data; // tavo AppDbContext

var builder = WebApplication.CreateBuilder(args);

// ====================== Config ======================
var connStr         = builder.Configuration.GetConnectionString("Postgres")
                         ?? throw new InvalidOperationException("Missing ConnectionStrings:Postgres");
var jwtIssuer       = builder.Configuration["Jwt:Issuer"]   ?? "https://localhost:5001";
var jwtAudience     = builder.Configuration["Jwt:Audience"] ?? "https://localhost:5001";
var jwtKey          = builder.Configuration["Jwt:Key"]
                         ?? throw new InvalidOperationException("Missing Jwt:Key");
var ghClientId      = builder.Configuration["Auth:GitHub:ClientId"];
var ghClientSecret  = builder.Configuration["Auth:GitHub:ClientSecret"];

// ====================== Services ======================
builder.Services.AddDbContext<AppDbContext>(opt =>
    opt.UseNpgsql(connStr));

builder.Services
    .AddIdentityCore<IdentityUser>(options =>
    {
        // Paprastesni reikalavimai laboratorijai
        options.Password.RequireDigit           = false;
        options.Password.RequireLowercase       = false;
        options.Password.RequireUppercase       = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredLength         = 6;
        options.User.RequireUniqueEmail         = true;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager();

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer           = true,
        ValidateAudience         = true,
        ValidateLifetime         = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer              = jwtIssuer,
        ValidAudience            = jwtAudience,
        IssuerSigningKey         = signingKey,
        ClockSkew                = TimeSpan.FromSeconds(30)
    };
});

builder.Services.AddAuthorization();
builder.Services.AddHttpClient();

var app = builder.Build();

// ====================== DB migracijos ======================
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate(); // jei turi pending, susikurk migraciją ir update
}

// ====================== Helpers ======================
string CreateJwt(IdentityUser user)
{
    var claims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer),
        new Claim(JwtRegisteredClaimNames.Aud, jwtAudience),
        new Claim(ClaimTypes.NameIdentifier, user.Id),
        new Claim(ClaimTypes.Name, user.UserName ?? "")
    };

    var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        notBefore: DateTime.UtcNow,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
}

// demo in-memory OAuth state
var oauthState = new HashSet<string>(StringComparer.Ordinal);





// Me
app.MapGet("/me", async (ClaimsPrincipal cp, UserManager<IdentityUser> userMgr) =>
{
    var userId = cp.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

    var user = await userMgr.FindByIdAsync(userId);
    if (user is null) return Results.NotFound();

    return Results.Ok(new
    {
        id = user.Id,
        email = user.Email,
        userName = user.UserName
    });
})
.RequireAuthorization();

// ===== GitHub OAuth =====
// /auth/login/github: redirect
app.MapGet("/auth/login/github", (HttpContext http) =>
{
    if (string.IsNullOrWhiteSpace(ghClientId) || string.IsNullOrWhiteSpace(ghClientSecret))
        return Results.BadRequest(new { error = "github_oauth_not_configured" });

    var request = http.Request;
    var origin = $"{request.Scheme}://{request.Host}";
    var redirectUri = $"{origin}/auth/callback/github";

    var state = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        .TrimEnd('=').Replace('+','-').Replace('/','_');
    oauthState.Add(state);

    var url = $"https://github.com/login/oauth/authorize" +
              $"?client_id={Uri.EscapeDataString(ghClientId!)}" +
              $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
              $"&scope={Uri.EscapeDataString("read:user user:email")}" +
              $"&state={Uri.EscapeDataString(state)}";

    return Results.Redirect(url);
});

// /auth/callback/github: code -> token -> user -> JWT
app.MapGet("/auth/callback/github", async (
    HttpContext http,
    IHttpClientFactory hf,
    UserManager<IdentityUser> userMgr) =>
{
    if (string.IsNullOrWhiteSpace(ghClientId) || string.IsNullOrWhiteSpace(ghClientSecret))
        return Results.BadRequest(new { error = "github_oauth_not_configured" });

    var code = http.Request.Query["code"].ToString();
    var state = http.Request.Query["state"].ToString();
    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state) || !oauthState.Remove(state))
        return Results.BadRequest(new { error = "invalid_state_or_code" });

    var origin = $"{http.Request.Scheme}://{http.Request.Host}";
    var redirectUri = $"{origin}/auth/callback/github";

    // 1) code -> access_token
    var client = hf.CreateClient();
    client.DefaultRequestHeaders.Accept.ParseAdd("application/json");

    var tokenRes = await client.PostAsync(
        "https://github.com/login/oauth/access_token",
        new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ghClientId!,
            ["client_secret"] = ghClientSecret!,
            ["code"] = code,
            ["redirect_uri"] = redirectUri
        }));

    if (!tokenRes.IsSuccessStatusCode)
        return Results.StatusCode((int)tokenRes.StatusCode);

    var tokenJson = System.Text.Json.JsonDocument.Parse(await tokenRes.Content.ReadAsStringAsync());
    if (!tokenJson.RootElement.TryGetProperty("access_token", out var atEl))
        return Results.BadRequest(new { error = "no_access_token" });

    var accessToken = atEl.GetString()!;

    // 2) user info iš GitHub
    var api = hf.CreateClient();
    api.DefaultRequestHeaders.UserAgent.ParseAdd("minimal-dotnet8-api");
    api.DefaultRequestHeaders.Authorization =
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

    var userRes = await api.GetAsync("https://api.github.com/user");
    if (!userRes.IsSuccessStatusCode) return Results.StatusCode((int)userRes.StatusCode);

    var uj = System.Text.Json.JsonDocument.Parse(await userRes.Content.ReadAsStringAsync()).RootElement;
    var ghId = uj.GetProperty("id").GetInt64().ToString();
    var login = uj.TryGetProperty("login", out var lg) ? lg.GetString() : null;
    string? email = null;

    // bandome gauti email
    var emailsRes = await api.GetAsync("https://api.github.com/user/emails");
    if (emailsRes.IsSuccessStatusCode)
    {
        var arr = System.Text.Json.JsonDocument.Parse(await emailsRes.Content.ReadAsStringAsync()).RootElement;
        foreach (var e in arr.EnumerateArray())
        {
            if (e.TryGetProperty("primary", out var pr) && pr.GetBoolean() &&
                e.TryGetProperty("email", out var em))
            { email = em.GetString(); break; }
        }
    }

    // 3) upsert IdentityUser
    IdentityUser? user = null;

    if (!string.IsNullOrWhiteSpace(email))
        user = await userMgr.FindByEmailAsync(email);

    if (user is null)
    {
        var userName = email ?? $"github_{ghId}";
        user = new IdentityUser
        {
            UserName = userName,
            Email = email,
            EmailConfirmed = true
        };
        var createRes = await userMgr.CreateAsync(user);
        if (!createRes.Succeeded)
            return Results.BadRequest(new { errors = createRes.Errors.Select(e => e.Description) });
    }

    // 4) JWT
    var jwt = CreateJwt(user);
    var originReq = $"{http.Request.Scheme}://{http.Request.Host}";
    var redirectTo = $"{originReq}/auth/done#access_token={Uri.EscapeDataString(jwt)}";
    return Results.Redirect(redirectTo);
});
// Minimalus HTML "Sign up with GitHub" + profilis
app.MapGet("/", () =>
{
    var html = """
<!doctype html>
<html lang="lt">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Sign up with GitHub demo</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; max-width: 720px; margin: 40px auto; padding: 0 16px; }
    button, a.btn { padding: 10px 14px; border-radius: 8px; border: 1px solid #ddd; background: #111; color: #fff; text-decoration: none; }
    .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-top: 16px; }
    img { border-radius: 50%; width: 72px; height: 72px; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Sign up with GitHub</h1>

  <p>
    <a class="btn" href="/auth/login/github">Continue with GitHub</a>
  </p>

  <div class="card">
    <h3>Profiliukas</h3>
    <div id="profile">Neprisijungta.</div>
  </div>

  <div class="card">
    <h3>Tokenas</h3>
    <pre id="token">–</pre>
  </div>

  <script>
    // 1) Jei grįžom iš GitHub, tokenas bus #access_token=...
    (function bootstrap() {
      const hash = new URLSearchParams(location.hash.slice(1));
      const token = hash.get("access_token");
      if (token) {
        sessionStorage.setItem("jwt", token);
        // nuvalom hash, kad neliktų istorijoje
        history.replaceState({}, document.title, location.pathname + location.search);
      }
      render();
      fetchMe();
    })();

    function render() {
      const t = sessionStorage.getItem("jwt");
      document.getElementById("token").textContent = t ? t : "–";
    }

    async function fetchMe() {
      const t = sessionStorage.getItem("jwt");
      const el = document.getElementById("profile");

      if (!t) {
        el.textContent = "Neprisijungta.";
        return;
      }
      try {
        const res = await fetch("/me", { headers: { Authorization: "Bearer " + t } });
        if (!res.ok) {
          el.textContent = "Nepavyko gauti profilio: " + res.status + " " + res.statusText;
          return;
        }
        const me = await res.json();
        el.innerHTML = `
          <div style="display:flex; gap:16px; align-items:center;">
            ${me.avatar ? `<img src="${me.avatar}" alt="avatar">` : ""}
            <div>
              <div><strong>ID:</strong> <code>${me.id}</code></div>
              <div><strong>Username:</strong> ${me.userName ?? ""}</div>
              <div><strong>Email:</strong> ${me.email ?? "–"}</div>
            </div>
          </div>
        `;
      } catch (e) {
        el.textContent = "Klaida: " + e;
      }
    }
  </script>
</body>
</html>
""";
    return Results.Content(html, "text/html; charset=utf-8");
});

// Paprastas home, jei nori mygtuko ir čia
app.MapGet("/signup", () =>
{
    var html = """
<!doctype html>
<html lang="lt">
  <meta charset="utf-8"/>
  <title>GitHub signup</title>
  <p><a class="btn" href="/auth/login/github" style="padding:10px 14px;border:1px solid #ddd;border-radius:8px;background:#111;color:#fff;text-decoration:none;">Sign up with GitHub</a></p>
  <p>Po prisijungimo būsi grąžintas į <code>/auth/done</code>, kur parodysime tavo profilį.</p>
</html>
""";
    return Results.Content(html, "text/html; charset=utf-8");
});


// ====================== Middleware ======================
app.UseAuthentication();
app.UseAuthorization();
app.Run();

// ====================== DTOs ======================
record RegisterDto(string Email, string Password);
record LoginDto(string Email, string Password);
