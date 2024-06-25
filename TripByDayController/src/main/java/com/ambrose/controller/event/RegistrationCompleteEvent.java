package com.ambrose.controller.event;


import com.ambrose.repository.entities.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

@Setter
@Getter
public class RegistrationCompleteEvent extends ApplicationEvent {

  private User user;
  //private String applicationUrl;

  public RegistrationCompleteEvent( User user) {
    super(user);
    this.user = user;
    //this.applicationUrl = applicationUrl;
  }
}
