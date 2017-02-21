package com.github.chencye.demo.jcryption.controller;

import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.http.HttpServletRequest;

public class ServletUtils {

	public static void printParams(HttpServletRequest request) {
		System.out.println("begin printParams...");
		Map<?, ?> map = request.getParameterMap();
		for (Entry<?, ?> entry : map.entrySet()) {
			Object value = entry.getValue();
			if (!value.getClass().isArray()) {
				System.out.println(entry.getKey() + " : " + value);
				continue;
			}
			String[] values = (String[]) value;
			for (String v : values) {
				System.out.println("array --> " + entry.getKey() + " : " + v);
			}
		}
		System.out.println("end printParams !");
	}
}
