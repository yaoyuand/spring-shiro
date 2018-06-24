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
	//��¼��֤
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
			credentials="038bdaf98f2037b31f1e75b5b4c9b26e";
		}else if("user".equals(username)){
			credentials="098d2c478e9c11555ce2823231e02ec1";
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
		String algorithmName="MD5";
		Object source="123456";
		Object salt="user";
		Integer hashIterations=1024;
		Object str=new SimpleHash(algorithmName, source, salt, hashIterations);
		System.out.println(str);
	}
	//��Ȩ��֤
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection 
			principals) {
		//��PrincipalCollection�з����û���¼��Ϣ
		Object user=principals.getPrimaryPrincipal();
		//���õ�¼��Ϣ���鿴�û���ǰȨ��(������Ҫ���ݿ��ѯ)
		Set<String> roles=new HashSet<>();
		roles.add("user");
		if("admin".equals(user))
			roles.add("admin");
		//����SimpleAuthorizationInfo����,������roles����
		SimpleAuthorizationInfo info=new SimpleAuthorizationInfo(roles);
		//����SimpleAuthorizationInfo����
		return info;
	}
	

}
