package com.example.demo.model;

import java.math.BigInteger;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToOne;
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
	private long sec_id;
	@Column(name = "security_ansid1")
	private String security_ansid1;
	@Column(name = "security_ansid2")
	private String security_ansid2;
	@Column(name = "security_queid1")
private long security_queid1;
	@Column(name = "security_queid2")
private long security_queid2 ;
 }
