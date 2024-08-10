package com.demo.userlogin.springsecuritylogin.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class Company {
    private String name;
    private String description;
    private String contactEmail;
    private String contactPhone;
}
