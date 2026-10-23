import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-dyn', template: '<div [innerHTML]="safeHtml"></div><p>{{ msg }}</p>' })
export class DynComponent {
  constructor(private translate: TranslateService, private sanitizer: any) {}
  msg = '';
  safeHtml: any;

  show(key: string, known: boolean) {
    if (known) {
      this.msg = this.translate.instant('KNOWN');
    } else {
      this.msg = this.translate.instant(key);
      this.safeHtml = this.sanitizer.bypassSecurityTrustHtml(this.msg);
    }
  }
}
