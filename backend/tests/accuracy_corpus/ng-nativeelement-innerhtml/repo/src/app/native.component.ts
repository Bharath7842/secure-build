import { Component } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';

@Component({ selector: 'app-native', template: '<p>{{ text }}</p>' })
export class NativeComponent {
  constructor(private translate: TranslateService) {}
  text = '';
  el: any;

  show(key: string) {
    this.text = this.translate.instant(key);
    this.el.nativeElement.innerHTML = this.text;
  }
}
