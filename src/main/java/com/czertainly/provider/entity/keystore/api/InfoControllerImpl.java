package com.czertainly.provider.entity.keystore.api;

import com.czertainly.api.interfaces.connector.InfoController;
import com.czertainly.api.model.client.connector.InfoResponse;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.provider.entity.keystore.EndpointsListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class InfoControllerImpl implements InfoController {
    private static final Logger logger = LoggerFactory.getLogger(InfoControllerImpl.class);

    @Autowired
    public void setEndpointsListener(EndpointsListener endpointsListener) {
        this.endpointsListener = endpointsListener;
    }

    private EndpointsListener endpointsListener;

    @Override
    public List<InfoResponse> listSupportedFunctions() {
        logger.info("Listing end points for Keystore Entity Provider");
        List<String> kinds = List.of("Keystore");
        List<InfoResponse> functions = new ArrayList<>();
        functions.add(new InfoResponse(kinds, FunctionGroupCode.ENTITY_PROVIDER, endpointsListener.getEndpoints()));

        return functions;
    }
}
