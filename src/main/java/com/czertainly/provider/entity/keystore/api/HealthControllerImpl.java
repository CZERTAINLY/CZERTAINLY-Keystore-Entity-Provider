package com.czertainly.provider.entity.keystore.api;

import com.czertainly.api.interfaces.connector.HealthController;
import com.czertainly.api.model.common.HealthDto;
import com.czertainly.provider.entity.keystore.service.HealthCheckService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthControllerImpl implements HealthController {

    @Autowired
    HealthCheckService healthCheckService;

    @Override
    public HealthDto checkHealth() {
        return healthCheckService.checkHealth();
    }
}
