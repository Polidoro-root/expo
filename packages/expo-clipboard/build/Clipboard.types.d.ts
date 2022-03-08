export interface GetImageOptions {
    /**
     * The format of the clipboard image to be converted to.
     */
    format: 'png' | 'jpeg';
    /**
     * Specify the quality of the returned image, between `0` and `1`. Defaults to `1` (highest quality).
     * Applicable only when `format` is set to `jpeg`, ignored otherwise.
     * @default 1
     */
    jpegQuality?: number;
}
export interface ClipboardImage {
    /**
     * A Base64-encoded string of the image data.
     * Its format is dependent on the `format` option.
     *
     * > **NOTE:** The string is already prepended with `data:image/png;base64,` or `data:image/jpeg;base64,` prefix.
     *
     * You can use it directly as the source of an `Image` element.
     * @example
     * ```ts
     * <Image
     *   source={{ uri: clipboardImage.data }}
     *   style={{ width: 200, height: 200 }}
     * />
     * ```
     */
    data: string;
    /**
     * Dimensions (`width` and `height`) of the image pasted from clipboard.
     */
    size: {
        width: number;
        height: number;
    };
}
export declare enum StringContentType {
    PLAIN_TEXT = "plainText",
    HTML = "html"
}
export interface GetStringOptions {
    /**
     * The target format of the clipboard string to be converted to, if possible.
     * Defaults to plain text.
     *
     * On web, this option is ignored. The string is always returned without any conversion.
     *
     * @default `StringContentType.PLAIN_TEXT`
     */
    preferredType?: StringContentType;
}
export interface SetStringOptions {
    /**
     * The input format of the provided string. Setting this helps other apps
     * to better interpret the copied string contents. Defaults to plain text.
     *
     * On web, this option is ignored. The string will be copied directly as-is, without any conversion.
     *
     * @default `StringContentType.PLAIN_TEXT`
     */
    inputType?: StringContentType;
}
//# sourceMappingURL=Clipboard.types.d.ts.map