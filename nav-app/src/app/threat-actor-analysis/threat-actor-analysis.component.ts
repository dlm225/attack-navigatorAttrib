import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { ViewModel } from '../classes/view-model';
import { DataService } from '../services/data.service';
import { Group } from '../classes/stix/group';

export interface ThreatActorMatch {
    group: Group;
    matchingTechniques: string[];
    selectedCoverage: number;  // % of selected techniques this actor covers
    actorCoverage: number;     // % of actor's techniques that are selected
    totalTechniques: number;   // Total techniques the actor uses
}

@Component({
    selector: 'app-threat-actor-analysis',
    templateUrl: './threat-actor-analysis.component.html',
    styleUrls: ['./threat-actor-analysis.component.scss']
})
export class ThreatActorAnalysisComponent {
    public topThreatActors: ThreatActorMatch[] = [];
    public selectedTechniques: string[] = [];
    public loading = false;
    public expandedDescriptions: Set<string> = new Set();

    constructor(
        public dialogRef: MatDialogRef<ThreatActorAnalysisComponent>,
        @Inject(MAT_DIALOG_DATA) public data: { viewModel: ViewModel },
        private dataService: DataService
    ) {
        this.analyzeThreatActors();
    }

    /**
     * Analyze threat actors based on selected techniques
     */
    private analyzeThreatActors(): void {
        this.loading = true;
        
        // Get all selected techniques from the view model
        this.selectedTechniques = this.getSelectedTechniques();
        console.log('Selected techniques found:', this.selectedTechniques);
        
        if (this.selectedTechniques.length === 0) {
            console.log('No selected techniques found');
            this.loading = false;
            return;
        }

        // Get threat actor matches
        const threatActorMatches = this.calculateThreatActorMatches();
        console.log('Threat actor matches found:', threatActorMatches.length);
        
        // Sort by selected coverage (descending), then by absolute count (descending), then by actor coverage
        this.topThreatActors = threatActorMatches
            .sort((a, b) => {
                if (b.selectedCoverage !== a.selectedCoverage) {
                    return b.selectedCoverage - a.selectedCoverage;
                }
                if (b.matchingTechniques.length !== a.matchingTechniques.length) {
                    return b.matchingTechniques.length - a.matchingTechniques.length;
                }
                return b.actorCoverage - a.actorCoverage;
            })
            .slice(0, 10);

        console.log('Top threat actors:', this.topThreatActors);
        this.loading = false;
    }

    /**
     * Get all selected techniques (colored + explicitly selected)
     */
    private getSelectedTechniques(): string[] {
        const selectedTechniques: string[] = [];
        const uniqueTechniques = new Set<string>();
        
        console.log('Total techniqueVMs:', this.data.viewModel.techniqueVMs.size);
        console.log('Selected techniques from viewModel:', Array.from(this.data.viewModel.selectedTechniques));
        
        // Get explicitly selected techniques
        for (const selectedId of this.data.viewModel.selectedTechniques) {
            const cleanTechniqueId = selectedId.split('^')[0];
            uniqueTechniques.add(cleanTechniqueId);
        }
        
        // Also include techniques that have colors applied (but aren't necessarily selected)
        for (const [techniqueId, tvm] of this.data.viewModel.techniqueVMs.entries()) {
            // Check if technique has manual color or score-based color
            if (tvm.color || (tvm.score && tvm.scoreColor)) {
                console.log(`Found colored technique: ${techniqueId}, color: ${tvm.color}, score: ${tvm.score}, scoreColor: ${tvm.scoreColor}`);
                
                // Extract just the technique ID part (remove tactic if present)
                // Format is "T1234.567^tactic" or just "T1234.567"
                const cleanTechniqueId = techniqueId.split('^')[0];
                uniqueTechniques.add(cleanTechniqueId);
            }
        }
        
        // Convert Set back to Array
        selectedTechniques.push(...Array.from(uniqueTechniques));
        
        return selectedTechniques;
    }

    /**
     * Calculate threat actor matches against colored techniques
     */
    private calculateThreatActorMatches(): ThreatActorMatch[] {
        const matches: ThreatActorMatch[] = [];
        const domain = this.dataService.getDomain(this.data.viewModel.domainVersionID);
        
        console.log('Domain:', domain);
        console.log('Domain ID:', this.data.viewModel.domainVersionID);
        
        if (!domain || !domain.groups) {
            console.log('No domain or groups found');
            return matches;
        }

        console.log('Number of groups:', domain.groups.length);

        let groupsChecked = 0;
        for (const group of domain.groups) {
            // Skip revoked or deprecated groups
            if (group.revoked || group.deprecated) {
                continue;
            }

            // Get techniques used by this group (returns STIX IDs)
            const groupTechniqueStixIds = group.used(this.data.viewModel.domainVersionID);
            
            if (groupTechniqueStixIds.length === 0) {
                continue;
            }

            // Convert STIX IDs to ATT&CK IDs
            const groupTechniques = this.convertStixIdsToAttackIds(groupTechniqueStixIds);

            // Log first few groups for debugging
            if (groupsChecked < 3) {
                console.log(`Group ${group.name} uses STIX IDs:`, groupTechniqueStixIds.slice(0, 5));
                console.log(`Group ${group.name} uses ATT&CK IDs:`, groupTechniques.slice(0, 5));
            }
            groupsChecked++;

            // Find intersection between selected techniques and group techniques
            const matchingTechniques = this.selectedTechniques.filter(techniqueId => 
                groupTechniques.includes(techniqueId)
            );

            if (matchingTechniques.length > 0) {
                // Primary: % of selected techniques this actor covers
                const selectedCoverage = (matchingTechniques.length / this.selectedTechniques.length) * 100;
                
                // Secondary: % of actor's techniques that are selected  
                const actorCoverage = (matchingTechniques.length / groupTechniques.length) * 100;
                
                console.log(`Group ${group.name} has ${matchingTechniques.length} matching techniques:`, matchingTechniques);
                console.log(`Selected coverage: ${selectedCoverage.toFixed(1)}%, Actor coverage: ${actorCoverage.toFixed(1)}%`);
                
                matches.push({
                    group: group,
                    matchingTechniques: matchingTechniques,
                    selectedCoverage: selectedCoverage,
                    actorCoverage: actorCoverage,
                    totalTechniques: groupTechniques.length
                });
            }
        }

        return matches;
    }

    /**
     * Convert STIX IDs to ATT&CK IDs using the domain data
     */
    private convertStixIdsToAttackIds(stixIds: string[]): string[] {
        const domain = this.dataService.getDomain(this.data.viewModel.domainVersionID);
        const attackIds: string[] = [];

        for (const stixId of stixIds) {
            // Look for the technique in both main techniques and subtechniques
            const technique = domain.techniques.find(t => t.id === stixId) || 
                             domain.subtechniques.find(t => t.id === stixId);
            
            if (technique && technique.attackID) {
                attackIds.push(technique.attackID);
            }
        }

        return attackIds;
    }

    /**
     * Toggle expanded description for a group
     */
    public toggleDescription(groupId: string): void {
        if (this.expandedDescriptions.has(groupId)) {
            this.expandedDescriptions.delete(groupId);
        } else {
            this.expandedDescriptions.add(groupId);
        }
    }

    /**
     * Check if description is expanded for a group
     */
    public isDescriptionExpanded(groupId: string): boolean {
        return this.expandedDescriptions.has(groupId);
    }

    /**
     * Close the dialog
     */
    public close(): void {
        this.dialogRef.close();
    }

    /**
     * Get technique name by ID
     */
    public getTechniqueName(techniqueId: string): string {
        const domain = this.dataService.getDomain(this.data.viewModel.domainVersionID);
        if (!domain) return techniqueId;
        
        const technique = domain.techniques.find(t => t.attackID === techniqueId);
        return technique ? technique.name : techniqueId;
    }
}