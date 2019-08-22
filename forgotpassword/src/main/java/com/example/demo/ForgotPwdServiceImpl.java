package com.example.demo;






import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class ForgotPwdServiceImpl implements ForgotPwdService{


	@Autowired
	private PersonDAO employeeDAO;

	
	@Override
	public boolean findByEmail(String email) {
		
		
		return employeeDAO.findByEmail(email)==1?true:false;
			
	}

	@Override
	public String findQuestionsById(String email) {
		
		return employeeDAO.findQuestionsById(email);
	}

	@Override
	public String findAnswersById(String email) {
		
		return employeeDAO.findAnswersById(email);
	}

	@Override
	@Transactional
	public boolean setPassword(String pass,String salt, String email) {
		
		
	   return employeeDAO.setPassword(pass,salt,email)==1?true:false;
		 
				
	}

	@Override
	@Transactional
	public void changeColumns(String email) {
		
		 employeeDAO.changeColumns(email);
	}

}
