package com.example.demo;



import java.util.ArrayList;
import java.util.List;



import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class ForgotPwdServiceImpl implements ForgotPwdService{


	@Autowired
	private PersonDAO employeeDAO;

	
	@Override
	public boolean findByEmail(String email) {
		// TODO Auto-generated method stub
		
		if(employeeDAO.findByEmail(email)==1)
			return true;
		return false;
	}

	@Override
	public String findQuestionsById(String email) {
		// TODO Auto-generated method stub
		return employeeDAO.findQuestionsById(email);
	}

	@Override
	public String findAnswersById(String email) {
		// TODO Auto-generated method stub
		return employeeDAO.findAnswersById(email);
	}

	@Override
	@Transactional
	public boolean setPassword(String pass,String salt, String email) {
		// TODO Auto-generated method stub
		
	   if(employeeDAO.setPassword(pass,salt,email)==1)
		   return true;
	   return false;
				
	}

	@Override
	@Transactional
	public void changeColumns(String email) {
		// TODO Auto-generated method stub
		 employeeDAO.changeColumns(email);
	}

}
