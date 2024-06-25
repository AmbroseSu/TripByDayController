package com.ambrose.controller.controller;

import com.ambrose.controller.config.ResponseUtil;
import com.ambrose.service.dto.GalleryDTO;
import com.ambrose.service.dto.ServiceDTO;
import com.ambrose.service.services.ServiceService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/service")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('CUSTOMER')")
public class ServiceController {

  @Autowired
  private ServiceService serviceService;

  @PostMapping("/save")
  public ResponseEntity<?> saveService(@RequestBody ServiceDTO serviceDTO){
    return serviceService.save(serviceDTO);
  }

  @PutMapping("update/{id}")
  public ResponseEntity<?> updateService(@RequestBody ServiceDTO serviceDTO, @PathVariable(name = "id") Long id){
    if (serviceService.checkExist(id)){
      serviceDTO.setId(id);
      return serviceService.save(serviceDTO);
    }
    return ResponseUtil.error("Not Found", "Gallery not exits", HttpStatus.NOT_FOUND);

  }

  @GetMapping("/find-id/{id}")
  //@PreAuthorize("hasAuthority('CUSTOMER')")
  public ResponseEntity<?> getServiceById(@PathVariable(name = "id") Long id){
    return serviceService.findById(id);
  }

  @GetMapping("/find-all")
  //@PreAuthorize("hasAuthority('CUSTOMER')")
  public ResponseEntity<?> getAllServiceByStatusTrue(@RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "10") int limit){
    return serviceService.findAllByStatusTrue(page, limit);
  }

  @DeleteMapping("/delete/{id}")
  public ResponseEntity<?> changeStatus(@PathVariable(name = "id") Long id){
    return serviceService.changeStatus(id);
  }

}
