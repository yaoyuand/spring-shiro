package com.shiro.realm;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class ShiroRealm extends AuthorizingRealm {
	//登录认证
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) 
			throws AuthenticationException {
		//1.获取传递的用户名
		UsernamePasswordToken uToken=(UsernamePasswordToken)token;
		String username=uToken.getUsername();
		//2.通过用户名去数据库表中查找信息
		System.out.println("数据库查找"+username+"信息");
		//3.如果用户不存在抛出异常
		if("unknow".equals(username))
			throw new UnknownAccountException("用户不存在!");
		if("lock".equals(username))
			throw new LockedAccountException("用户被锁定!");
		//4.根据用户情况返回AuthenticationInfo,通常返回SimpleAuthenticationInfo对象
		//1).principal认证的实体信息，可以为username,也可以是数据库表中对象
		Object principal=username;
		//2).credentials:密码
		Object credentials="";
		if("admin".equals(username)){
			credentials="038bdaf98f2037b31f1e75b5b4c9b26e";
		}else if("user".equals(username)){
			credentials="098d2c478e9c11555ce2823231e02ec1";
		}
		//3).获取盐值
		ByteSource credentialsSalt=ByteSource.Util.bytes(username);
		//3).realmName:当前Realm对象的name,调用父类的getName()方法即可
		String realmName=getName();
//		SimpleAuthenticationInfo info=new SimpleAuthenticationInfo(principal, credentials, realmName);
		SimpleAuthenticationInfo info=new SimpleAuthenticationInfo(principal, credentials, credentialsSalt, realmName);
		return info;
	}
	public static void main(String[] args) {
		String algorithmName="MD5";
		Object source="123456";
		Object salt="user";
		Integer hashIterations=1024;
		Object str=new SimpleHash(algorithmName, source, salt, hashIterations);
		System.out.println(str);
	}
	//授权认证
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection 
			principals) {
		//从PrincipalCollection中返回用户登录信息
		Object user=principals.getPrimaryPrincipal();
		//利用登录信息来查看用户当前权限(可能需要数据库查询)
		Set<String> roles=new HashSet<>();
		roles.add("user");
		if("admin".equals(user))
			roles.add("admin");
		//创建SimpleAuthorizationInfo对象,设置其roles属性
		SimpleAuthorizationInfo info=new SimpleAuthorizationInfo(roles);
		//返回SimpleAuthorizationInfo对象
		return info;
	}
	

}
