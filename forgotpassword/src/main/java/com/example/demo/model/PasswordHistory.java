package com.example.demo.model;




import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.stereotype.Component;

import lombok.Data;
@Data
@Entity
@Table(name = "password_history")
@Component
public class PasswordHistory   {
	

	
	@Id
	@GeneratedValue(strategy =GenerationType.AUTO )
	@Column(name = "pass_id")
	private long  passId;
	@Column(name = "password1")
	private String password1 ;
	@Column(name = "password2")
	private String password2 ;
	@Column(name = "password3")
private 	String password3 ;
	@Column(name = "salt1")
	private String salt1;
	@Column(name = "salt2")
	private String salt2;
	@Column(name = "salt3")
	private String  salt3 ;
	

}
