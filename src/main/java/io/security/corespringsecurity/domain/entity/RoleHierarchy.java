package io.security.corespringsecurity.domain.entity;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE_HIERARCHY")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString(exclude = {"parentName, roleHierarchies"})
public class RoleHierarchy implements Serializable {

    @Id @GeneratedValue
    private Long id;

    private String childName;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "parentName", referencedColumnName = "childName")
    private RoleHierarchy parentName;

    @OneToMany(mappedBy = "parentName", cascade = CascadeType.ALL)
    private Set<RoleHierarchy> roleHierarchies = new HashSet<>();

}
