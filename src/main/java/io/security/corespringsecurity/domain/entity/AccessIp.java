package io.security.corespringsecurity.domain.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Data
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessIp implements Serializable {

    @Id @GeneratedValue
    @Column(name = "IP_ID")
    private Long id;

    @Column(nullable = false)
    private String ipAddress;
}
