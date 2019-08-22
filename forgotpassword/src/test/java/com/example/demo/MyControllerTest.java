package com.example.demo; 

  

import static org.junit.Assert.*; 
import org.junit.Before; 

import org.junit.Test; 

import org.springframework.http.MediaType; 

import org.springframework.test.web.servlet.MvcResult; 

import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.example.demo.model.Person; 

  

  

public class MyControllerTest extends AbstractTestClass { 
	String email="shaikneha823@gmail.com";
     @Override 
       @Before 
       public void setUp() { 
          super.setUp(); 
  } 

       @Test 
       public void mailCheck() throws Exception { 

          String uri = "/forgotpassword/uic"; 

         Person person=new Person(); 

          person.setEmail(email); 

          String inputJson = super.mapToJson(person); 

          MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post(uri) 

             .contentType(MediaType.APPLICATION_JSON_VALUE) 

             .content(inputJson)).andReturn(); 

           

          int status = mvcResult.getResponse().getStatus(); 

          assertEquals(200, status); 

         String content = mvcResult.getResponse().getContentAsString(); 

          

          assertEquals(content,"{\"status\":\"true\"}"); 

       } 

   

    @Test 

    public void getChoice() throws Exception { 

        String uri = "/forgotpassword/mts"; 

         Person person=new Person(); 
          person.setEmail(email);
          person.setChoice("3"); 

          String inputJson = super.mapToJson(person); 

          MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post(uri) 

             .contentType(MediaType.APPLICATION_JSON_VALUE) 

             .content(inputJson)).andReturn(); 

           

          int status = mvcResult.getResponse().getStatus(); 

          assertEquals(200, status); 

         String content = mvcResult.getResponse().getContentAsString(); 

          

          assertEquals(content,"{\"question1\":\"What is your favorite team?\",\"question2\":\"What is your favorite movie?\"}"); 

       } 

    @Test 

    public void getSecurityQuestionsTest() throws Exception { 

        String uri = "/forgotpassword/sec"; 

         Person person=new Person(); 
         person.setEmail(email);
          person.setAns2("pink"); 

          person.setAns1("rcb"); 

          String inputJson = super.mapToJson(person); 

          MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post(uri) 

             .contentType(MediaType.APPLICATION_JSON_VALUE) 

             .content(inputJson)).andReturn(); 

           

          int status = mvcResult.getResponse().getStatus(); 

          assertEquals(200, status); 

         String content = mvcResult.getResponse().getContentAsString(); 

          

          assertEquals(content,"{\"status\":\"true\"}"); 

       } 

    
    } 
