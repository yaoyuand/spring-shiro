package com.shiro.factory;

import java.util.LinkedHashMap;

public class FilterMap {
	public LinkedHashMap<String, String> FilterMapBuilder(){
		LinkedHashMap<String, String> map=new LinkedHashMap<>();
		map.put("/login.jsp", "anon");
		map.put("/shiro/login", "anon");
		map.put("/**", "authc");
		return map;
	}

}
