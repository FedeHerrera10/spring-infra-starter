package com.fedeherrera.testUtil;

import org.springframework.stereotype.Controller;

import com.fedeherrera.infra.controller.BaseAuthController;
import com.fedeherrera.infra.service.auth.AuthService;
import com.fedeherrera.infra.service.user.UserService;
import com.fedeherrera.infra.service.verification.VerificationService;
import com.fedeherrera.infra.entity.BaseUser;
import com.fedeherrera.infra.entity.BaseVerificationToken;

@Controller
public class AuthControllerTest extends BaseAuthController<BaseUser, BaseVerificationToken> {

    public AuthControllerTest(AuthService<BaseUser, BaseVerificationToken> authService,
            VerificationService<BaseUser, BaseVerificationToken> verificationService,
            UserService<BaseUser> userService) {
        super(authService, verificationService, userService);
    }
}
