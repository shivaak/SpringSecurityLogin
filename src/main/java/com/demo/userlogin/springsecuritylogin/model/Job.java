package com.demo.userlogin.springsecuritylogin.model;

import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class Job {
    private String id;
    private String title;
    private String type;
    private String description;
    private String location;
    private String salary;
    private Company company;

    public Job(String title, String type, String description, String location, String salary,
            Company company) {
        this.id = UUID.randomUUID().toString();
        this.title = title;
        this.type = type;
        this.description = description;
        this.location = location;
        this.salary = salary;
        this.company = company;
    }
}