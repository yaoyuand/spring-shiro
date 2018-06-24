package com.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

public class SecondRealm extends AuthenticatingRealm {

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
			credentials="ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
		}else if("user".equals(username)){
			credentials="073d4c3ae812935f23cb3f2a71943f49e082a718";
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
		String algorithmName="SHA1";
		Object source="123456";
		Object salt="admin";
		Integer hashIterations=1024;
		Object str=new SimpleHash(algorithmName, source, salt, hashIterations);
		System.out.println(str);
	}
	

}
