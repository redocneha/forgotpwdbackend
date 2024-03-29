package com.example.demo.model;



	import org.springframework.security.crypto.bcrypt.BCrypt;
	import org.springframework.security.crypto.password.PasswordEncoder;

	 

	public class CustomPasswordEncoder implements PasswordEncoder {

	 

	    public String encodeWithSalt(CharSequence rawPassword, String salt){
	        return BCrypt.hashpw(rawPassword.toString(), salt);
	    }
	    
	    @Override
	    public String encode(CharSequence rawPassword) {
	       
	        return null;
	    }

	 

	    @Override
	    public boolean matches(CharSequence rawPassword, String encodedPassword) {
	       
	        return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
	    }

	 

	}
	 
