import { ClipboardImage, GetImageOptions } from './Clipboard.types';
declare const _default: {
    readonly name: string;
    getStringAsync(): Promise<string>;
    setString(text: string): boolean;
    setStringAsync(text: string): Promise<boolean>;
    getImageAsync(_options: GetImageOptions): Promise<ClipboardImage | null>;
    setImageAsync(base64image: string): Promise<void>;
    hasImageAsync(): Promise<boolean>;
    addClipboardListener(): void;
    removeClipboardListener(): void;
};
export default _default;
//# sourceMappingURL=ExpoClipboard.web.d.ts.map