package com.ambrose.controller.controller;

import com.ambrose.controller.config.ResponseUtil;
import com.ambrose.service.dto.CityDTO;
import com.ambrose.service.dto.GalleryDTO;
import com.ambrose.service.services.CityService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
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
@RequestMapping("/api/v1/city")
@RequiredArgsConstructor
@PreAuthorize("hasAuthority('CUSTOMER')")
public class CityController {

  @Autowired
  private CityService cityService;

  @PostMapping("/save")
  public ResponseEntity<?> saveCity(@RequestBody CityDTO cityDTO){
    return cityService.save(cityDTO);
  }

  @PutMapping("update/{id}")
  public ResponseEntity<?> updateCity(@RequestBody CityDTO cityDTO, @PathVariable(name = "id") Long id){
    if (cityService.checkExist(id)){
      cityDTO.setId(id);
      return cityService.save(cityDTO);
    }
    return ResponseUtil.error("Not Found", "Gallery not exits", HttpStatus.NOT_FOUND);
  }

  @GetMapping("/find-id/{id}")
  public ResponseEntity<?> getCityById(@PathVariable(name = "id") Long id){
    return cityService.findById(id);
  }

  @GetMapping("/find-all")
  public ResponseEntity<?> getAllCityByStatusTrue(@RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "10") int limit){
    return cityService.findAllByStatusTrue(page, limit);
  }

  @DeleteMapping("/delete/{id}")
  public ResponseEntity<?> changeStatus(@PathVariable(name = "id") Long id){
    return cityService.changeStatus(id);
  }
}
