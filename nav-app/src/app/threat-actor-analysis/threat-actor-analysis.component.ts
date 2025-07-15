import { Component, Inject } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';
import { ViewModel } from '../classes/view-model';
import { DataService } from '../services/data.service';
import { Group } from '../classes/stix/group';

export interface ThreatActorMatch {
    group: Group;
    matchingTechniques: string[];
    matchPercentage: number;
    totalTechniques: number;
}

@Component({
    selector: 'app-threat-actor-analysis',
    templateUrl: './threat-actor-analysis.component.html',
    styleUrls: ['./threat-actor-analysis.component.scss']
})
export class ThreatActorAnalysisComponent {
    public topThreatActors: ThreatActorMatch[] = [];
    public coloredTechniques: string[] = [];
    public loading = false;

    constructor(
        public dialogRef: MatDialogRef<ThreatActorAnalysisComponent>,
        @Inject(MAT_DIALOG_DATA) public data: { viewModel: ViewModel },
        private dataService: DataService
    ) {
        this.analyzeThreatActors();
    }

    /**
     * Analyze threat actors based on colored techniques
     */
    private analyzeThreatActors(): void {
        this.loading = true;
        
        // Get all colored techniques from the view model
        this.coloredTechniques = this.getColoredTechniques();
        console.log('Colored techniques found:', this.coloredTechniques);
        
        if (this.coloredTechniques.length === 0) {
            console.log('No colored techniques found');
            this.loading = false;
            return;
        }

        // Get threat actor matches
        const threatActorMatches = this.calculateThreatActorMatches();
        console.log('Threat actor matches found:', threatActorMatches.length);
        
        // Sort by match percentage (descending) then by absolute count (descending)
        this.topThreatActors = threatActorMatches
            .sort((a, b) => {
                if (b.matchPercentage !== a.matchPercentage) {
                    return b.matchPercentage - a.matchPercentage;
                }
                return b.matchingTechniques.length - a.matchingTechniques.length;
            })
            .slice(0, 10);

        console.log('Top threat actors:', this.topThreatActors);
        this.loading = false;
    }

    /**
     * Get all techniques that have colors applied
     */
    private getColoredTechniques(): string[] {
        const coloredTechniques: string[] = [];
        
        for (const [techniqueId, tvm] of this.data.viewModel.techniqueVMs.entries()) {
            // Check if technique has manual color or score-based color
            if (tvm.color || (tvm.score && tvm.scoreColor)) {
                coloredTechniques.push(techniqueId);
            }
        }
        
        return coloredTechniques;
    }

    /**
     * Calculate threat actor matches against colored techniques
     */
    private calculateThreatActorMatches(): ThreatActorMatch[] {
        const matches: ThreatActorMatch[] = [];
        const domain = this.dataService.getDomain(this.data.viewModel.domainVersionID);
        
        if (!domain || !domain.groups) {
            return matches;
        }

        for (const group of domain.groups) {
            // Skip revoked or deprecated groups
            if (group.revoked || group.deprecated) {
                continue;
            }

            // Get techniques used by this group
            const groupTechniques = group.used(this.data.viewModel.domainVersionID);
            
            if (groupTechniques.length === 0) {
                continue;
            }

            // Find intersection between colored techniques and group techniques
            const matchingTechniques = this.coloredTechniques.filter(techniqueId => 
                groupTechniques.includes(techniqueId)
            );

            if (matchingTechniques.length > 0) {
                const matchPercentage = (matchingTechniques.length / groupTechniques.length) * 100;
                
                matches.push({
                    group: group,
                    matchingTechniques: matchingTechniques,
                    matchPercentage: matchPercentage,
                    totalTechniques: groupTechniques.length
                });
            }
        }

        return matches;
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