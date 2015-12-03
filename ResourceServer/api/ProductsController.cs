using System;
using System.Collections.Generic;
using System.Web.Http;
using System.Security.Claims;

namespace ResourceServer.api
{
    [RoutePrefix("api")]
    [Authorize(Roles = "PowerUsers")]
    public class ProductsController : ApiController
    {
        [Route("products")]
        public IHttpActionResult Get()
        {
            var identity = User.Identity as ClaimsIdentity;

            IList<Models.Product> products = new List<Models.Product>();

            products.Add(new Models.Product() { Code = 1, Description = "Jam" });
            products.Add(new Models.Product() { Code = 2, Description = "Milk" });
            products.Add(new Models.Product() { Code = 3, Description = "Bread" });

            return Ok(products);
        }
    }
}
