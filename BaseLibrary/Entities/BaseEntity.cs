﻿using System.Text.Json.Serialization;

namespace BaseLibrary.Entities
{
    public class BaseEntity
    {
        public int Id { get; set; }
        public String? Name { get; set; }

        // Relationship one to many
        [JsonIgnore]
        public List<Employee>? Employees { get; set; }

    }
}
