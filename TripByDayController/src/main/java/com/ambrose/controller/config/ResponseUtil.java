package com.ambrose.controller.config;





import com.ambrose.service.dto.MeatadataDTO;
import com.ambrose.service.dto.ResponseDTO;
import java.util.List;
import lombok.experimental.UtilityClass;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@UtilityClass
public class ResponseUtil {

  public static ResponseEntity<ResponseDTO> getObject(Object result, HttpStatus status,
      String response) {
    return new ResponseEntity<>(
        ResponseDTO.builder()
            .details(ExceptionUtils.getResponseString(response))
            .content(result)
            .statusCode(status.value())
            .build()
        , status
    );
  }

  public static ResponseEntity<?> getCollection(Object result, HttpStatus status, String response
      , int page, int limit, long count) {
    return new ResponseEntity<>(
        ResponseDTO.builder()
            .statusCode(status.value())
            .details(ExceptionUtils.getResponseString(response))
            .content(result)
            .meatadataDTO(getMeatadata(page, limit, count))
            .build()
        , status
    );
  }

  public MeatadataDTO getMeatadata(int page, int limit, long count) {
    MeatadataDTO result = new MeatadataDTO();
    result.setPage(page);
    result.setTotal(((int) Math.ceil((double) count / limit)));
    result.setLimit(limit);
    if (limit <= count) {
      result.setHasNextPage(false);
      result.setHasPrevPage(false);
    } else {
      if (result.getPage() > 1 && result.getPage() < result.getTotal()) {
        result.setHasNextPage(true);
        result.setHasPrevPage(true);
      }
      if (result.getPage() == 1) {
        result.setHasNextPage(false);
        result.setHasPrevPage(true);
      }
      if (result.getPage() == result.getTotal()) {
        result.setHasNextPage(false);
        result.setHasPrevPage(true);
      }
    }
    return result;

  }

  public static ResponseEntity<?> error(String error, String message, HttpStatus status) {
    return new ResponseEntity<>(
        ResponseDTO.builder()
            .message(message)
            .details(ExceptionUtils.getError(error))
            .statusCode(status.value())
            .build()
        , status
    );
  }

  public static ResponseEntity<?> error(List<String> errors, String message, HttpStatus status) {
    return new ResponseEntity<>(
        ResponseDTO.builder()
            .message(message)
            .details(errors)
            .statusCode(status.value())
            .build()
        , status
    );
  }
}
