package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.demo.model.CustomPasswordEncoder;

@Configuration
public class ForgotpasswordConfig {
@Bean
	public CustomPasswordEncoder custompasswordencoder()
	{
	return new CustomPasswordEncoder();
	}

}
