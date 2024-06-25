package com.ambrose.controller.config;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.experimental.UtilityClass;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@UtilityClass
public class ConstraintViolationExceptionHandler {
  public static ResponseEntity<?> handleConstraintViolation(ConstraintViolationException e) {
    Set<ConstraintViolation<?>> violations = e.getConstraintViolations();
    List<String> errorMessages = violations.stream()
        .map(violation -> String.format("%s %s", violation.getPropertyPath(), violation.getMessage()))
        .collect(Collectors.toList());

    // Join error messages for a detailed error message
    String detailedErrorMessage = String.join(", ", errorMessages);
    // Use the first error message as a user-friendly message
    String userFriendlyMessage = errorMessages.isEmpty() ? "Validation failed" : errorMessages.get(0);

    // Return a ResponseEntity with an error using ResponseUtil
    return ResponseUtil.error(detailedErrorMessage, "Bad request", HttpStatus.BAD_REQUEST);
  }
}