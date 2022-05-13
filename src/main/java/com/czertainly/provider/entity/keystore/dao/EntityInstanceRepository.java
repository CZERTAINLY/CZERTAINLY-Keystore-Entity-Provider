package com.czertainly.provider.entity.keystore.dao;

import com.czertainly.provider.entity.keystore.dao.entity.EntityInstance;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EntityInstanceRepository extends JpaRepository<EntityInstance, Long> {

    Optional<EntityInstance> findByName(String name);

    Optional<EntityInstance> findByUuid(String uuid);
}
