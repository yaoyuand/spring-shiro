package com.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/shiro")
public class ShiroController {
	@RequestMapping("/login")
	public String login(@RequestParam("username")String username,
			@RequestParam("password")String password){
		Subject subject=SecurityUtils.getSubject();
		if(!subject.isAuthenticated()){
			UsernamePasswordToken token=new UsernamePasswordToken(username, password);
			token.setRememberMe(true);
			try {
				subject.login(token);
			}catch(UnknownAccountException unknow){
				System.out.println("�û�������:"+unknow.getMessage());
			}catch(IncorrectCredentialsException incorr){
				System.out.println("�������:"+incorr.getMessage());
			}catch(LockedAccountException lock){
				System.out.println("�û�������:"+lock.getMessage());
			} catch (AuthenticationException e) {
				System.out.println("��¼ʧ��:"+e.getMessage());
			}
		}
		return "redirect:/list.jsp";
	}
}
