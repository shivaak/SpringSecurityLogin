package com.demo.userlogin.springsecuritylogin.model;

public enum Role {
    ROLE_USER(2006),
    ROLE_ADMIN(1901);

    private final int value;

    Role(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
