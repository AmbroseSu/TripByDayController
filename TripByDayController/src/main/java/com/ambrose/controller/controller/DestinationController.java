package com.ambrose.controller.controller;

import com.ambrose.controller.config.ResponseUtil;
import com.ambrose.service.dto.DestinationDTO;
import com.ambrose.service.dto.GalleryDTO;
import com.ambrose.service.services.DestinationService;
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
@RequestMapping("/api/v1/destination")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('CUSTOMER')")
public class DestinationController {

  @Autowired
  private DestinationService destinationService;

  @PostMapping("/save")
  public ResponseEntity<?> saveDestination(@RequestBody DestinationDTO destinationDTO){
    return destinationService.save(destinationDTO);
  }

  @PutMapping("update/{id}")
  public ResponseEntity<?> updateDestination(@RequestBody DestinationDTO destinationDTO, @PathVariable(name = "id") Long id){
    if (destinationService.checkExist(id)){
      destinationDTO.setId(id);
      return destinationService.save(destinationDTO);
    }
    return ResponseUtil.error("Not Found", "Gallery not exits", HttpStatus.NOT_FOUND);
  }

  @GetMapping("/find-id/{id}")
  public ResponseEntity<?> getDestinationById(@PathVariable(name = "id") Long id){
    return destinationService.findById(id);
  }

  @GetMapping("/find-all")
  //@PreAuthorize("hasAuthority('CUSTOMER')")
  public ResponseEntity<?> getAllDestinationByStatusTrue(@RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "10") int limit){
    return destinationService.findAllByStatusTrue(page, limit);
  }

  @DeleteMapping("/delete/{id}")
  public ResponseEntity<?> changeStatus(@PathVariable(name = "id") Long id){
    return destinationService.changeStatus(id);
  }

}
