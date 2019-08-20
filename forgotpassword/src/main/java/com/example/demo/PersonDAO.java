package com.example.demo;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.example.demo.model.Person;
@Repository
public interface PersonDAO extends CrudRepository<Person,Long> {
	  @Query("SELECT sq1.question,sq2.question FROM SecurityQuestions sq1,SecurityQuestions sq2 where (sq1.questionid,sq2.questionid) in  (select sa.security_queid1,sa.security_queid2 from SecurityAns sa where sa.sec_id in( select p.secAnswers from Register p WHERE p.emailid=:email))")
    String findQuestionsById(@Param("email")String email) ;
	  @Query("select sa.security_ansid1,sa.security_ansid2 from SecurityAns sa where sa.sec_id in( select p.pwdhistory from Register p WHERE p.emailid=:email)")

    String findAnswersById(@Param("email")String  email);
    @Query("SELECT count(*) FROM Register p WHERE p.emailid=:email")
    public int findByEmail(@Param("email") String email);
    @Modifying(clearAutomatically=true)
    @Query("Update PasswordHistory p set p.password3=p.password2,p.password2=p.password1,p.salt3=p.salt2,p.salt2=p.salt1 where p.pass_id =(select r.pwdhistory from Register r where r.emailid=:email)")
   
    public void changeColumns(@Param("email") String email);
    @Modifying(clearAutomatically=true)
    
 @Query("UPDATE PasswordHistory p set p.password1=:password,p.salt1=:salt  WHERE p.pass_id=(select r.pwdhistory from Register r where r.emailid=:email)")
 int setPassword(@Param("password") String password,@Param("salt") String salt,@Param("email") String email);

}
