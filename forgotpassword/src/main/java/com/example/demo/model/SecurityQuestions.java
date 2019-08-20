package com.example.demo.model;

import java.io.Serializable;
import java.math.BigInteger;

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
@Table(name="security_questions")
@Component
public class SecurityQuestions implements Serializable {
	
	@Id
	@GeneratedValue(strategy =GenerationType.AUTO)
	@Column(name = "questionid")
	private long questionid ;
	@Column(name = "question")
	private String question;
	
}
