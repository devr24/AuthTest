using Microsoft.EntityFrameworkCore;

namespace AuthTest.Entities
{
    public class UpsertTodoItem
    {
        public string? Name { get; set; }
        public bool IsComplete { get; set; }
    }

    public class TodoItem
    {
        public long Id { get; set; }
        public string? Name { get; set; }
        public bool IsComplete { get; set; }
    }
}
