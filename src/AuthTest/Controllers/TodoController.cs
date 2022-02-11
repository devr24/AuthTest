using AuthTest.Data;
using AuthTest.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TodoController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public TodoController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Policy = "AdminOnly")]
        [HttpGet("auth/adminPolicyTest")]
        public IActionResult GetAdminOnly()
        {
            return Ok("Hello world!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("auth/adminRoleTest")]
        public IActionResult GetAdminRole()
        {
            return Ok("Hello world!");
        }

        [Authorize]
        [HttpGet("auth/test")]
        public IActionResult GetAuthTest()
        {
            return Ok("Hello world!");
        }

        // GET: api/<TodoController>
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            return Ok(await _context.TodoItems.ToListAsync());
        }

        // GET api/<TodoController>/5
        [HttpGet("{id}")]
        public async Task<IActionResult> GetValue(long? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var todoItem = await _context.TodoItems
                .FirstOrDefaultAsync(m => m.Id == id);
            if (todoItem == null)
            {
                return NotFound();
            }

            return Ok(todoItem);
        }

        // POST api/<TodoController>
        [HttpPost]
        public async Task<IActionResult> Post([FromBody] UpsertTodoItem todoItem)
        {
            if (ModelState.IsValid)
            {
                var item = _context.Add(new TodoItem
                {
                    IsComplete = todoItem.IsComplete,
                    Name = todoItem.Name
                });
                await _context.SaveChangesAsync();

                return CreatedAtAction(nameof(GetValue), new { id = item.Entity.Id }, item.Entity);
            }
            return BadRequest();
        }

        // PUT api/<TodoController>/5
        [HttpPut("{id}")]
        public async Task<IActionResult> Put(int id, [FromBody] UpsertTodoItem todoItem)
        {
            var foundItem = _context.TodoItems.FirstOrDefault(t => t.Id == id);
            if (foundItem == null)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    foundItem.Name = todoItem.Name;
                    foundItem.IsComplete = todoItem.IsComplete;

                    _context.Update(foundItem);
                    await _context.SaveChangesAsync();
                    return Ok(todoItem);
                }
                catch (DbUpdateConcurrencyException)
                {
                    throw;
                }
            }
            return BadRequest();
        }

        // DELETE api/<TodoController>/5
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(long? id)
        {
            if (id == null || !TodoItemExists(id.Value))
            {
                return NotFound();
            }

            var todoItem = await _context.TodoItems
                .FirstOrDefaultAsync(m => m.Id == id);
            if (todoItem == null)
            {
                return NotFound();
            }

            _context.Remove(todoItem);
            await _context.SaveChangesAsync();

            return Ok(todoItem);
        }

        private bool TodoItemExists(long id)
        {
            return _context.TodoItems.Any(e => e.Id == id);
        }
    }
}
