package com.example.demo.model;

import java.math.BigInteger;
import java.sql.Timestamp;
import java.util.Date;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.springframework.stereotype.Component;

import lombok.Data;
@Data
@Entity
@Component
@Table(name="register")
public class Register {
	@Id
	@Column(name = "userid")
	@GeneratedValue(strategy=GenerationType.AUTO)
	private long userid;
	@Transient
	private Date date = new Date();
	@Column(name = "account_creation_time")
	Timestamp account_creation_time = new Timestamp(date.getTime());
	@Column(name = "email_confirmation_flag")
	private boolean email_confirmation_flag;
	@Column(name = "emailid")
	 private String emailid;
	@Column(name = "first_name")
	private  String first_name;
	@Column(name = "last_name")
	private String last_name ;
	@Column(name = "phoneno")
	private String phone_no ;
	@Column(name = "userrole")
	private String user_role ;
	@OneToOne(fetch=FetchType.EAGER,cascade=CascadeType.ALL)
	private PasswordHistory pwdhistory;
	
	@OneToOne(fetch=FetchType.EAGER,cascade=CascadeType.ALL)
	private SecurityAns secAnswers;
	 
	
}
