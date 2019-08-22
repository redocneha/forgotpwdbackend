package com.example.demo;



import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import com.example.demo.model.CustomPasswordEncoder;
import com.example.demo.model.Person;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
@RestController
@RequestMapping("/forgotpassword")
public class MyController {
	 private final Logger logger = LoggerFactory.getLogger(this.getClass());
	String email;
	@Autowired
	private CustomPasswordEncoder cpe;
	@Autowired
	private JavaMailSender javaMailSender;
	@Autowired
	private ForgotPwdService fgps=new ForgotPwdServiceImpl();
	@Autowired
	private ObjectMapper mapper;
	String otp;
	@CrossOrigin(origins= "*")

	@PostMapping("/uic")
	
	public String getValidation( @RequestBody Person p) {
	logger.info("validating email......");
	logger.debug("retrieving entered email address.....");
		String p1=p.getEmail();
		email=p1;
		ObjectNode jsonObject = mapper.createObjectNode();
		logger.debug("jsonObject initialised......");
		
		if(fgps.findByEmail(p1))
		{
			logger.info("email successfully authenticated......");
			jsonObject.put("status", "true");
			
		}
		else
		{
			
			logger.warn("Unregistered email......");
			jsonObject.put("status", "false");
		}
		String str=jsonObject.toString();
		
		 logger.debug("returning the json object to react.....");
		return str;
   
     
                   }
	@RequestMapping("/")
	public String demo()
	{
		return "hi";
	}
	@CrossOrigin(origins="*")
	@PostMapping("/otp")
	public String validateOTP( @RequestBody Person p) {
		logger.info("Validating OTP......");
		ObjectNode jsonObject = mapper.createObjectNode();
		logger.debug("jsonObject initialised......");
	if(p.getOtp().equals(otp))
	{
		logger.info("Entered OTP is valid......");
		jsonObject.put("status", "true");
	}
	else
	{
		logger.warn("Invalid OTP......");
		jsonObject.put("status", "false");
	}
	String str=jsonObject.toString();
	logger.debug("returning the json object to react.....");
	return str;
	}
	

	
	@CrossOrigin(origins="*")
	@PostMapping("/mts")
	public String  methodToSet( @RequestBody Person p) {
		
	String email=p.getEmail();
	logger.debug("retrieving email......");
	ObjectNode jsonObject = mapper.createObjectNode();
	logger.debug("jsonObject initialised......");
	String  c=p.getChoice();
	logger.info("User Selected {}......",c);
	System.out.println(c);
	if(c.equals("2")) {
		
			SimpleMailMessage msg = new SimpleMailMessage();
			msg.setTo(email);
			
			msg.setSubject("OTP For Forgot Password");
			otp = String.valueOf((long) (Math.random() * 9000) + 1000);
			msg.setText("Your OTP is :" + otp);
			logger.info("Sending OTP......");
			javaMailSender.send(msg);
			logger.info("OTP sent......");

		jsonObject.put("otp", otp);
		  
	}
	
   if(c.equals("3")) {
	   logger.debug("finding security questions of the user......");
	   String al=fgps.findQuestionsById(email);
	   logger.debug("security questions retrieved successfully......");
	  al= al.replace('[', ' ');
	  al= al.replace(']', ' ');
	  String[] q=al.split(",");
	   jsonObject.put("question1", q[0]);
	  
	   jsonObject.put("question2", q[1]);
	   
	  
	  

    
	        
	}
   String str=jsonObject.toString();
   logger.debug("returning the json object to react.....");
	return str;

	}
	
 
	
	@CrossOrigin(origins="*")
	@PostMapping("/sec")
	public String security( @RequestBody Person p) {
		 logger.info("checking the entered answers......");
		
			ObjectNode jsonObject = mapper.createObjectNode();
	    if(securityQuestionsCheck(p))
	    {
	    	logger.info("Entered answers are correct......");
	    	  jsonObject.put("status", "true");
	    	 
	    }
		
		else
		{
			logger.warn("Entered answers are Incorrect......");
			 jsonObject.put("status", "false");
		      
	    	  
		}
	    String str=jsonObject.toString();
	    logger.debug("returning the json object to react.....");
		return str;
		}
		
	
	private boolean securityQuestionsCheck(Person p) {
		// TODO Auto-generated method stub
		 logger.debug("inside  securityQuestionsCheck......");
	String email=p.getEmail();
	 logger.debug("retrieving email......");

	 logger.debug("retrieving the answers given by the user......");

		String al=fgps.findAnswersById(email);
		 
		  al= al.replace('[', ' ');
		  al= al.replace(']', ' ');
		  String[] q=al.split(",");
		  logger.debug("Answers given by the users retrieved......");
		   
		
	if(q[0].equals(p.getAns1())&&q[1].equals(p.getAns2()))
	{
		logger.debug("succesfully validated the answers and sending back to called method......");

		return true;
	}
	else {
		logger.debug("succesfully validated the answers and sending back to called method......");

		return false;
	}
	}
	
	@CrossOrigin(origins= "*")
	@PostMapping("/set")
	public String setPassword( @RequestBody Person p) {
		
		ObjectNode jsonObject = mapper.createObjectNode();
		logger.info("Setting new password......");
		
		String pass=p.getPassword();
		logger.debug("getting password from front end.....");
		
		String salt=BCrypt.gensalt(12);
		logger.debug("generating salt .....");
		String hashedPassword=cpe.encodeWithSalt(pass, salt);
		logger.debug("generating hashed password .....");
		fgps.changeColumns(email);
		logger.debug("shifting the column data  of passwords.....");
		if(fgps.setPassword(hashedPassword,salt,email))
		{
			logger.info(" password succesfully set.....");
			jsonObject.put("status", "true");
		}
		else
		{
			logger.info(" password is not set succesfully.....");
		
	    	  jsonObject.put("status", "false");
		}
	    	  String str=jsonObject.toString();
	  		logger.debug("returning the json object to react.....");

	  		return str;
	      
	    }
}
