using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using WebBackend.Data;
using WebBackend.Services;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var configuration = builder.Configuration;

builder.Services.AddControllers();
builder.Services.AddHttpClient();

// Ensure the JWT Key is not null or empty; provide a default if necessary
var jwtKey = configuration["JWT:Key"] ?? throw new ArgumentNullException("JWT:Key is missing in configuration. Please add it to appsettings.json.");

// Register services
services.AddSingleton<WebBackendMongoDbContext>();
services.AddScoped<UserService>();
services.AddScoped<PasswordService>();
services.AddScoped<JwtService>();
services.AddScoped<OtpService>();
services.AddScoped<GoogleAuthService>();
services.AddSingleton<EmailService>(); // Ensure this line is present

// Configure JWT Authentication
services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = configuration["JWT:Issuer"],
        ValidAudience = configuration["JWT:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

// Add authorization services
services.AddAuthorization();

// Add Swagger with JWT support
services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "MyWebApi", Version = "v1" });

    // Add JWT Authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\nExample: 'Bearer abcdef12345'"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "MyWebApi V1"));
}

// Middleware
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();  // Maps controller endpoints

app.Run();
