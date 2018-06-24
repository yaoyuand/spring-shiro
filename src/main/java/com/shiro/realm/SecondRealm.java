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
		//1.��ȡ���ݵ��û���
		UsernamePasswordToken uToken=(UsernamePasswordToken)token;
		String username=uToken.getUsername();
		//2.ͨ���û���ȥ���ݿ���в�����Ϣ
		System.out.println("���ݿ����"+username+"��Ϣ");
		//3.����û��������׳��쳣
		if("unknow".equals(username))
			throw new UnknownAccountException("�û�������!");
		if("lock".equals(username))
			throw new LockedAccountException("�û�������!");
		//4.�����û��������AuthenticationInfo,ͨ������SimpleAuthenticationInfo����
		//1).principal��֤��ʵ����Ϣ������Ϊusername,Ҳ���������ݿ���ж���
		Object principal=username;
		//2).credentials:����
		Object credentials="";
		if("admin".equals(username)){
			credentials="ce2f6417c7e1d32c1d81a797ee0b499f87c5de06";
		}else if("user".equals(username)){
			credentials="073d4c3ae812935f23cb3f2a71943f49e082a718";
		}
		//3).��ȡ��ֵ
		ByteSource credentialsSalt=ByteSource.Util.bytes(username);
		//3).realmName:��ǰRealm�����name,���ø����getName()��������
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
