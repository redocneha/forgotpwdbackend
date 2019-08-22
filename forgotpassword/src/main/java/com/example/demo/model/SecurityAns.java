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
@Component
@Table(name="security_ans")
public class SecurityAns {
	
	@Id
	@GeneratedValue(strategy =GenerationType.AUTO)
	@Column(name = "sec_id")
	private long secId;
	@Column(name = "security_ansid1")
	private String securityAnsid1;
	@Column(name = "security_ansid2")
	private String securityAnsid2;
	@Column(name = "security_queid1")
private long securityQueid1;
	@Column(name = "security_queid2")
private long securityQueid2 ;
 }
