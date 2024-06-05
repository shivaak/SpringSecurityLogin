package com.demo.userlogin.springsecuritylogin;

import com.demo.userlogin.springsecuritylogin.config.TestSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestSecurityConfig.class)
class SpringsecurityloginApplicationTests {

    @Test
    void contextLoads() {
    }

}
