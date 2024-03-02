/*
 * Copyright (C) 2017-2024 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.sapl.server.ce.ui.views.digitalpolicies;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.data.provider.CallbackDataProvider;
import com.vaadin.flow.data.provider.DataProvider;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;

import io.sapl.server.ce.model.sapldocument.SaplDocument;
import io.sapl.server.ce.model.sapldocument.SaplDocumentService;
import io.sapl.server.ce.ui.views.MainLayout;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

/**
 * View for listening and managing SAPL documents. A Designer generated
 * component for the list-sapl-documents template.
 */
//@RolesAllowed("ADMIN")
@PermitAll
@RequiredArgsConstructor
@PageTitle("Digital Policies")
@Route(value = DigitalPoliciesView.ROUTE, layout = MainLayout.class)
public class DigitalPoliciesView extends VerticalLayout {

    public static final String ROUTE = "";

    private final transient SaplDocumentService saplDocumentService;

    private final Grid<SaplDocument> saplDocumentGrid = new Grid<>();
    private final Button             createButton     = new Button("Create");

    @PostConstruct
    private void init() {
        add(createButton, saplDocumentGrid);

        initSaplDocumentGrid();

        createButton.addClickListener(clickEvent -> {
            saplDocumentService.createDefault();
            saplDocumentGrid.getDataProvider().refreshAll();
        });

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        /*
         * OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal)
         * authentication.getPrincipal();
         * System.out.println(authentication.getAuthorities() + " " +
         * authentication.getPrincipal());
         *
         * String givenName = principal.getAttribute("given_name"); String familyName =
         * principal.getAttribute("family_name"); String email =
         * principal.getAttribute("email"); String picture =
         * principal.getAttribute("picture"); String role =
         * principal.getAttribute("roles");
         *
         * System.out.println(givenName + " " + familyName + " " + email + " " + role);
         */
    }

    private void initSaplDocumentGrid() {
        // add columns
        saplDocumentGrid.addColumn(SaplDocument::getName).setHeader("Name");
        saplDocumentGrid.addColumn(SaplDocument::getCurrentVersionNumber).setHeader("Version");
        saplDocumentGrid.addColumn(SaplDocument::getPublishedVersionNumberAsString).setHeader("Published Version");
        saplDocumentGrid.addColumn(SaplDocument::getLastModified).setHeader("Last Modified");
        saplDocumentGrid.addColumn(SaplDocument::getTypeAsString).setHeader("Type");
        saplDocumentGrid.getColumns().forEach(col -> col.setAutoWidth(true));
        saplDocumentGrid.addComponentColumn(saplDocument -> {
            Button editButton = new Button("Edit", VaadinIcon.EDIT.create());
            editButton.addClickListener(clickEvent -> {
                String uriToNavigateTo = String.format("%s/%d", EditSaplDocumentView.ROUTE, saplDocument.getId());
                editButton.getUI().ifPresent(ui -> ui.navigate(uriToNavigateTo));
            });
            editButton.setThemeName("primary");

            HorizontalLayout componentsForEntry = new HorizontalLayout();
            componentsForEntry.add(editButton);
            return componentsForEntry;
        });

        // set data provider
        CallbackDataProvider<SaplDocument, Void> dataProvider = DataProvider.fromCallbacks(query -> {
            int offset = query.getOffset();
            int limit  = query.getLimit();

            return saplDocumentService.getAll().stream().skip(offset).limit(limit);
        }, query -> (int) saplDocumentService.getAmount());
        saplDocumentGrid.setItems(dataProvider);

        saplDocumentGrid.setAllRowsVisible(true);
    }
}
