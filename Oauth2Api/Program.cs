using System.Globalization;
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
    .AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager();

var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
builder.Services.AddAuthentication()
.AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
    
        ValidIssuer              = jwtIssuer,
        ValidAudience            = jwtAudience,
        IssuerSigningKey         = signingKey,
    };
});
builder.Services.AddRazorPages();
builder.Services.AddAuthorization();
builder.Services.AddHttpClient();

var app = builder.Build();


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






// Me
app.MapGet("/me", async (HttpContext http, UserManager<IdentityUser> userMgr) =>
{
    var cp = http.User;
    var userId = cp.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId))
    {
        return Results.Unauthorized();
    }

    var user = await userMgr.FindByIdAsync(userId);
    if (user is null)
    {
        return Results.Unauthorized();
    }

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


    var request = http.Request;
    var origin = $"{request.Scheme}://{request.Host}";
    var redirectUri = $"{origin}/auth/callback/github";

    var state = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        .TrimEnd('=').Replace('+','-').Replace('/','_');


    var url = $"https://github.com/login/oauth/authorize" +
              $"?client_id={Uri.EscapeDataString(ghClientId!)}" +
              $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
              $"&scope={Uri.EscapeDataString("read:user user:email repo")}" +
              $"&state={Uri.EscapeDataString(state)}";

    return Results.Redirect(url);
});
app.MapGet("/repos", async (ClaimsPrincipal cp, AppDbContext db) =>
{
    var userId = cp.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

    var repos = await db.Repositories
        .Where(r => r.UserId == userId)
        .OrderByDescending(r => r.UpdatedAt)
        .Select(r => new
        {
            r.GitHubId,
            r.Name,
            r.FullName,
            r.HtmlUrl,
            r.Private,
            r.Description,
            r.UpdatedAt
        })
        .ToListAsync();

    return Results.Ok(repos);
}).RequireAuthorization();

// /auth/callback/github: code -> token -> user -> JWT
app.MapGet("/auth/callback/github", async (
    HttpContext http,
    IHttpClientFactory hf,
    UserManager<IdentityUser> userMgr) =>
{

var code = http.Request.Query["code"].ToString();
var state = http.Request.Query["state"].ToString();

    var origin = $"{http.Request.Scheme}://{http.Request.Host}";
    var redirectUri = $"{origin}/auth/callback/githubss";

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
    var accesstkn = tokenJson.RootElement.GetProperty("access_token");

    var accessToken = accesstkn.GetString()!;


    // 2) user info iš GitHub
    var api = hf.CreateClient();
    api.DefaultRequestHeaders.UserAgent.ParseAdd("minimal-dotnet8-api");
    api.DefaultRequestHeaders.Authorization =
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

    int page = 1;
    const int perPage = 100;
    var repos = new List<System.Text.Json.JsonElement>();

    while (true)
    {
        var rres = await api.GetAsync($"https://api.github.com/user/repos");
        if (!rres.IsSuccessStatusCode) break;

        var txt = await rres.Content.ReadAsStringAsync();
        var doc = System.Text.Json.JsonDocument.Parse(txt).RootElement;
        var arr = doc.EnumerateArray().ToArray();
        if (arr.Length == 0) break;

        repos.AddRange(arr);
        if (arr.Length < perPage) break;
        page++;
    }


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
        var loginIdent = uj.GetProperty("login").GetString();

        user = new IdentityUser
        {
            UserName = loginIdent,
            Email = email,
            EmailConfirmed = true
        };
        var createRes = await userMgr.CreateAsync(user);
        if (!createRes.Succeeded)
            return Results.BadRequest(new { errors = createRes.Errors.Select(e => e.Description) });
    }
    // repos
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        foreach (var r in repos)
        {
            var ghIdr = r.GetProperty("id").GetInt64();
            var name = r.GetProperty("name").GetString() ?? "";
            var fullName = r.GetProperty("full_name").GetString() ?? "";
            var htmlUrl = r.GetProperty("html_url").GetString() ?? "";
            var isPrivate = r.TryGetProperty("private", out var p) && p.GetBoolean();
            var desc = r.TryGetProperty("description", out var d) && d.ValueKind != System.Text.Json.JsonValueKind.Null ? d.GetString() : null;
            var updatedAt = r.TryGetProperty("updated_at", out var u)
    ? DateTimeOffset.Parse(
        u.GetString()!, 
        CultureInfo.InvariantCulture, 
        DateTimeStyles.RoundtripKind
      ).UtcDateTime
    : DateTime.UtcNow;

            var existing = await db.Repositories
                .FirstOrDefaultAsync(x => x.UserId == user.Id && x.GitHubId == ghIdr);

            if (existing is null)
            {
                db.Repositories.Add(new Repository
                {
                    UserId = user.Id,
                    GitHubId = ghIdr,
                    Name = name,
                    FullName = fullName,
                    HtmlUrl = htmlUrl,
                    Private = isPrivate,
                    Description = desc,
                    UpdatedAt = updatedAt
                });
            }
            else
            {
                existing.Name = name;
                existing.FullName = fullName;
                existing.HtmlUrl = htmlUrl;
                existing.Private = isPrivate;
                existing.Description = desc;
                existing.UpdatedAt = updatedAt;
            }

        }
        await db.SaveChangesAsync();
        // JWT
        var jwt = CreateJwt(user);
        var originReq = $"{http.Request.Scheme}://{http.Request.Host}";
        var redirectTo = $"{originReq}/auth/done#access_token={Uri.EscapeDataString(jwt)}";
        return Results.Redirect(redirectTo);

    } 
});

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.Run();


