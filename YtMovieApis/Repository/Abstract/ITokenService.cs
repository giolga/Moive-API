﻿using System.Security.Claims;
using YtMovieApis.Models.DTO;

namespace YtMovieApis.Repository.Abstract
{
    public interface ITokenService
    {
        TokenResponse GetToken(IEnumerable<Claim> claim);
        string GetRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
