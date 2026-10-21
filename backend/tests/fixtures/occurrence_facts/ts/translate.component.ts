import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-x', template: '' })
export class TranslateComponent {
  constructor(private translate: TranslateService) {}

  show(key: string, count: number) {
    this.translate.instant(key);
    console.log('count ' + count);
  }
}
