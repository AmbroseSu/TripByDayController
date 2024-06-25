package com.ambrose.controller.controller;

import com.ambrose.controller.config.ResponseUtil;
import com.ambrose.service.dto.GalleryDTO;
import com.ambrose.service.services.GalleryService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
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
@RequestMapping("/api/v1/gallery")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('CUSTOMER')")
public class GalleryController {

  @Autowired
  private GalleryService galleryService;

  @PostMapping("/save")
  public ResponseEntity<?> saveGallery(@RequestBody GalleryDTO galleryDTO){
    return galleryService.save(galleryDTO);
  }

  @PutMapping ("update/{id}")
  public ResponseEntity<?> updateGellery(@RequestBody GalleryDTO galleryDTO, @PathVariable(name = "id") Long id){
    if (galleryService.checkExist(id)){
      galleryDTO.setId(id);
      return galleryService.save(galleryDTO);
    }
    return ResponseUtil.error("Not Found", "Gallery not exits", HttpStatus.NOT_FOUND);

  }

  @GetMapping("/find-id/{id}")
  //@PreAuthorize("hasAuthority('CUSTOMER')")
  public ResponseEntity<?> getGalleryById(@PathVariable(name = "id") Long id){
    return galleryService.findById(id);
  }


  @GetMapping("/find-all")
  //@PreAuthorize("hasAuthority('CUSTOMER')")
  public ResponseEntity<?> getAllGalleryByStatusTrue(@RequestParam(defaultValue = "1") int page,
                                                     @RequestParam(defaultValue = "10") int limit){
    return galleryService.findAllByStatusTrue(page, limit);
  }

  @DeleteMapping("/delete/{id}")
  public ResponseEntity<?> changeStatus(@PathVariable(name = "id") Long id){
    return galleryService.changeStatus(id);
  }




}
