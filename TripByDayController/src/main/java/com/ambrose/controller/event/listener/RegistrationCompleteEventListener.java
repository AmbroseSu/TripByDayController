package com.ambrose.controller.event.listener;


import com.ambrose.controller.event.RegistrationCompleteEvent;
import com.ambrose.repository.entities.User;
import com.ambrose.service.services.UserService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import java.util.Random;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class RegistrationCompleteEventListener implements ApplicationListener<RegistrationCompleteEvent> {

  private final UserService userService;
  private final JavaMailSender mailSender;
  private User theUser;
  @Override
  public void onApplicationEvent(RegistrationCompleteEvent event) {

    theUser = event.getUser();
    //String verificationToken = UUID.randomUUID().toString();
    Random random = new Random();

    // Tạo một số ngẫu nhiên có 5 chữ số
    int min = 100000; // Số nhỏ nhất có 5 chữ số
    int max = 999999; // Số lớn nhất có 5 chữ số
    int randomNumber = random.nextInt(max - min + 1) + min;

    userService.saveUserVerificationToken(theUser, String.valueOf(randomNumber));


    String url = String.valueOf(randomNumber);

    try {
      sendVerificationEmail(url);
    } catch (MessagingException | UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }

    log.info("Click the link to verify your registration : {}", url);
  }


  public void sendVerificationEmail(String url)
      throws MessagingException, UnsupportedEncodingException {
    String subject = "Email Verification";
    String senderName = "User Registration Portal Service";
    String mailContent = "<p> Hi, "+ /*theUser.getFullname()+ */"</p>"+
        "<p>Thank you for registering with us,"+"" +
        "Please, follow the link below to complete your registration.</p>"+
        //"<a href=\"" +url+ "\">Verify your email to activate your account</a>"+
        url+
        "<p> Thank you <br> Users Registration Portal Service";
    MimeMessage message = mailSender.createMimeMessage();
    var messageHelper = new MimeMessageHelper(message);
    messageHelper.setFrom("haconghieu2003@gmail.com", senderName);
    messageHelper.setTo(theUser.getEmail());
    messageHelper.setSubject(subject);
    messageHelper.setText(mailContent, true);
    mailSender.send(message);
  }


}
