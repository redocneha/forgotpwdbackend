package com.example.demo.model;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;




@Entity

public class Person{
	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	private static final int serialVersionUID = 1;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	
	private int id;
	@Column(name = "email")
private String email;
@Override
public String toString() {
	return "Person [email=" + email + "]";
}


@Column(name = "otp")
private String otp;
public String getOtp() {
	return otp;
}
public void setOtp(String otp) {
	this.otp = otp;

}
@Column(name = "password")
private String password;
@Column(name = "ans1")
private String ans1;
@Column(name = "ans2")
private String ans2;
@Column(name = "ques1")
private String ques1;
public int getId() {
	return id;
}
public void setId(int id) {
	this.id = id;
}
public String getQues1() {
	return ques1;
}
public void setQues1(String ques1) {
	this.ques1 = ques1;
}
public String getQues2() {
	return ques2;
}
public void setQues2(String ques2) {
	this.ques2 = ques2;
}

@Column(name = "ques2")
private String ques2;
public String getAns1() {
	return ans1;
}
public void setAns1(String ans1) {
	this.ans1 = ans1;
}
public String getAns2() {
	return ans2;
}
public void setAns2(String ans2) {
	this.ans2 = ans2;
}
public String getChoice() {
	return choice;
}
public void setChoice(String choice) {
	this.choice = choice;
}

private String choice;

public String getEmail() {
	return email;
}
public void setEmail(String email) {
	this.email = email;
}
public String getPassword() {
	return password;
}
public void setPassword(String password) {
	this.password = password;
}

}
